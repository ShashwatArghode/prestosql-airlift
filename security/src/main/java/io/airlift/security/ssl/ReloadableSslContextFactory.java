package io.airlift.security.ssl;

import io.airlift.log.Logger;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.net.ssl.X509ExtendedKeyManager;

import java.io.IOException;
import java.net.URI;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.util.function.Consumer;

import static java.nio.file.StandardWatchEventKinds.ENTRY_MODIFY;

public class ReloadableSslContextFactory
        extends SslContextFactory
{
    public static final Logger LOG = Logger.get(ReloadableSslContextFactory.class);
    private SslContextWatcher sslContextWatcher;

    public ReloadableSslContextFactory(boolean trustAll)
    {
        super(trustAll);
    }

    @Override
    protected void doStart()
            throws Exception
    {
        super.doStart();
        sslContextWatcher = new SslContextWatcher(this);
        sslContextWatcher.start();
    }

    @Override
    protected void doStop()
            throws Exception
    {
        if (sslContextWatcher != null) {
            sslContextWatcher.stop();
        }
        super.doStop();
    }

    private static class SslContextWatcher
            implements Runnable
    {
        private Path keyStorePath;
        private Path trustStorePath;
        private WatchService watcher;
        private final SslContextFactory sslContextFactory;
        private final Consumer<SslContextFactory> sslContextFactoryConsumer = (x) -> {};
        private volatile boolean stopped;
        private Thread sslContextWatcher;

        SslContextWatcher(final SslContextFactory sslContextFactory)
                throws IOException
        {
            if (sslContextFactory.getKeyStorePath() != null) {
                // Remove leading "file://" from keyStorePath
                URI keyStoreURI = URI.create(sslContextFactory.getKeyStorePath());
                keyStorePath = Paths.get(keyStoreURI.getPath());
                Path keyStoreDir = keyStorePath.getParent();
                this.watcher = keyStoreDir.getFileSystem().newWatchService();
                keyStoreDir.register(watcher, ENTRY_MODIFY);
            }

            if (sslContextFactory.getTrustStorePath() != null) {
                // Remove leading "file://" from trustStorePath
                URI trustStoreURI = URI.create(sslContextFactory.getTrustStorePath());
                trustStorePath = Paths.get(trustStoreURI.getPath());
                Path trustStoreDir = trustStorePath.getParent();
                if (this.watcher == null) {
                    this.watcher = trustStoreDir.getFileSystem().newWatchService();
                }
                trustStoreDir.register(watcher, ENTRY_MODIFY);
            }
            this.sslContextFactory = sslContextFactory;
        }

        void start()
        {
            sslContextWatcher = new Thread(this);
            sslContextWatcher.setDaemon(true);
            sslContextWatcher.start();
        }

        void stop()
        {
            this.stopped = true;
            sslContextWatcher.interrupt();
        }

        @Override
        public void run()
        {
            while (!stopped) {
                WatchKey watchKey;
                try {
                    watchKey = watcher.take();
                }
                catch (InterruptedException e) {
                    LOG.warn(e, "keyStoreWatcher thread interrupted");
                    return;
                }
                for (WatchEvent event : watchKey.pollEvents()) {
                    if (ENTRY_MODIFY.equals(event.kind())) {
                        if ((keyStorePath != null && event.context().equals(keyStorePath.getFileName()))
                                || (trustStorePath != null && event.context().equals(trustStorePath.getFileName()))) {
                            try {
                                sslContextFactory.reload(sslContextFactoryConsumer);
                                LOG.info("Reloaded SSL credentials");
                                break;
                            }
                            catch (Throwable t) {
                                LOG.warn(t, "Error reloading SSL credentials");
                            }
                        }
                    }
                }
                watchKey.reset();
            }
        }
    }

    public static class Server
            extends SslContextFactory.Server
    {
        private ReloadableSslContextFactory.SslContextWatcher sslContextWatcher;

        @Override
        protected void doStart()
                throws Exception
        {
            super.doStart();
            sslContextWatcher = new ReloadableSslContextFactory.SslContextWatcher(this);
            sslContextWatcher.start();
        }

        @Override
        protected void doStop()
                throws Exception
        {
            if (sslContextWatcher != null) {
                sslContextWatcher.stop();
            }
            super.doStop();
        }
    }

    public static class Client
            extends ReloadableSslContextFactory
    {
        public Client()
        {
            this(false);
        }

        public Client(boolean trustAll)
        {
            super(trustAll);
        }

        protected void checkConfiguration()
        {
            this.checkTrustAll();
            this.checkEndPointIdentificationAlgorithm();
            super.checkConfiguration();
        }

        protected X509ExtendedKeyManager newSniX509ExtendedKeyManager(X509ExtendedKeyManager keyManager)
        {
            return keyManager;
        }
    }
}
