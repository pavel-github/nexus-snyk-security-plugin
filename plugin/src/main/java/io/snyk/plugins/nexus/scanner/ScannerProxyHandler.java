package io.snyk.plugins.nexus.scanner;

import javax.annotation.Nonnull;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.sonatype.nexus.repository.proxy.ProxyHandler;
import org.sonatype.nexus.repository.view.Context;
import org.sonatype.nexus.repository.view.Response;

@Named
@Singleton
public class ScannerProxyHandler extends ProxyHandler {

  @Inject
  private Provider<ScannerModule> scannerModule;

  @Nonnull
  @Override
  public Response handle(@Nonnull Context context) throws Exception {
    Response response = super.handle(context);
    scannerModule.get().scanComponent(context);
    return response;
  }
}
