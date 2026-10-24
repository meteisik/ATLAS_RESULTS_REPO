import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V1_SaffronFlareSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteSaffronFlareAccount() throws SQLException {
        String data;
        data = System.getenv("SAFFRON_FLARE_ACCOUNT_ID");
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V1_SaffronFlareSafeSink()).applySaffronFlareDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V1_SaffronFlareSafeSink {
    public void applySaffronFlareDeletion(CWE284_P09_V1_SaffronFlareSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection saffronFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronFlare");
        try {
            PreparedStatement saffronFlareDelete = saffronFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronFlareDelete.setString(1, data);
            if (authorized) {
                saffronFlareDelete.executeUpdate();
            }
        } finally {
            saffronFlareConnection.close();
        }
    }
}
