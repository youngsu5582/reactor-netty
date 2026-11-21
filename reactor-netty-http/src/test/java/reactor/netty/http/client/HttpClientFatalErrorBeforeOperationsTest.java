/*
 * Copyright (c) 2026 VMware, Inc. or its affiliates, All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package reactor.netty.http.client;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslHandshakeCompletionEvent;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import io.netty.pkitesting.CertificateBuilder;
import io.netty.pkitesting.X509Bundle;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import reactor.core.Disposable;
import reactor.core.publisher.Mono;
import reactor.netty.BaseHttpTest;
import reactor.netty.Connection;
import reactor.netty.ConnectionObserver;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A TLS handshake that fails while the connection has no {@code ChannelOperations} yet reaches
 * {@code ChannelOperationsHandler#exceptionCaught} through the {@code listener.onUncaughtException} branch.
 * The response {@code Mono} has to terminate with that failure, and the connection observers have to
 * receive the original error.
 * <p>
 * In the reported scenario the cause is a {@code java.lang.OutOfMemoryError: Cannot reserve ... bytes of
 * direct buffer memory} thrown from {@code SslHandler#unwrap}. {@code SslHandler#handleUnwrapThrowable}
 * fails the handshake future with it as is, fires {@code SslHandshakeCompletionEvent(cause)} and closes the channel;
 * {@code SslProvider$SslReadHandler} turns that event into {@code ctx.fireExceptionCaught(cause)}.
 * The test fires the same event, so it needs neither real memory pressure nor a real unwrap failure.
 * <p>
 * The first test is the control, with an ordinary exception. The second one uses an
 * {@code OutOfMemoryError}: Reactor rethrows a JVM fatal error ({@code Exceptions#throwIfFatal}) instead
 * of signalling it, and Netty logs and swallows what the handler threw, so the error has to be wrapped
 * before it is signalled to the {@code Mono}, as {@code ChannelOperations#wrapInboundError} does on the
 * branch that has operations.
 */
class HttpClientFatalErrorBeforeOperationsTest extends BaseHttpTest {

	static final int TERMINATION_TIMEOUT_SECONDS = 5;

	static X509Bundle ssc;

	@BeforeAll
	static void createSelfSignedCertificate() throws Exception {
		ssc = new CertificateBuilder().subject("CN=localhost").setIsCertificateAuthority(true).buildSelfSigned();
	}

	@Test
	void ordinaryHandshakeFailureTerminatesTheResponseMono() throws Exception {
		assertTerminates(new IllegalStateException("simulated TLS handshake failure"));
	}

	@Test
	void outOfMemoryErrorDuringHandshakeTerminatesTheResponseMono() throws Exception {
		assertTerminates(new OutOfMemoryError("simulated: Cannot reserve 524288 bytes of direct buffer memory"));
	}

	private void assertTerminates(Throwable cause) throws Exception {
		SslContext sslServer = SslContextBuilder.forServer(ssc.toTempCertChainPem(), ssc.toTempPrivateKeyPem()).build();
		SslContext sslClient = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build();

		disposableServer =
				createServer()
				        .secure(spec -> spec.sslContext(sslServer))
				        .handle((req, res) -> res.sendString(Mono.just("ok")))
				        .bindNow();

		CountDownLatch terminated = new CountDownLatch(1);
		CountDownLatch notified = new CountDownLatch(1);
		AtomicReference<Throwable> signalled = new AtomicReference<>();
		AtomicReference<Throwable> observed = new AtomicReference<>();

		Disposable exchange =
				createClient(disposableServer.port())
				        .secure(spec -> spec.sslContext(sslClient))
				        .observe(new ConnectionObserver() {
				            @Override
				            public void onStateChange(Connection connection, State newState) {
				            }

				            @Override
				            public void onUncaughtException(Connection connection, Throwable error) {
				                observed.compareAndSet(null, error);
				                notified.countDown();
				            }
				        })
				        // the handler is first in the pipeline, so the event passes the SslHandler and reaches
				        // SslReadHandler, while the TLS handshake is not done and there are no ChannelOperations yet
				        .doOnChannelInit((observer, channel, remoteAddress) ->
				                channel.pipeline().addFirst("handshakeFailure", new ChannelInboundHandlerAdapter() {
				                    @Override
				                    public void channelActive(ChannelHandlerContext ctx) {
				                        ctx.fireUserEventTriggered(new SslHandshakeCompletionEvent(cause));
				                        ctx.close();
				                    }
				                }))
				        .get()
				        .uri("/")
				        .responseContent()
				        .aggregate()
				        .asString()
				        .subscribe(v -> terminated.countDown(), e -> {
				            signalled.set(e);
				            terminated.countDown();
				        }, terminated::countDown);

		try {
			assertThat(terminated.await(TERMINATION_TIMEOUT_SECONDS, TimeUnit.SECONDS))
					.as("the response Mono must emit a terminal signal (value, error or complete) for %s", cause)
					.isTrue();
			assertThat(rootCause(signalled.get())).as("the Mono is terminated by the handshake failure").isSameAs(cause);
			// the observers are notified after the Mono is signalled, so wait for them as well
			assertThat(notified.await(TERMINATION_TIMEOUT_SECONDS, TimeUnit.SECONDS)).as("the observers are notified").isTrue();
			assertThat(observed.get()).as("the observers receive the original error").isSameAs(cause);
		}
		finally {
			exchange.dispose();
		}
	}

	static Throwable rootCause(Throwable error) {
		Throwable root = error;
		while (root != null && root.getCause() != null) {
			root = root.getCause();
		}
		return root;
	}
}
