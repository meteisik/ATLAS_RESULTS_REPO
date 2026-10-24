import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_AmberFlareSafe {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteAmberFlareAccount() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("AMBER_FLARE_ACCOUNT_ID");
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_AmberFlareSafeSink()).applyAmberFlareDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_AmberFlareSafeSink {
    public void applyAmberFlareDeletion(CWE284_P09_V2_AmberFlareSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection amberFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberFlare");
        try {
            PreparedStatement amberFlareDelete = amberFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberFlareDelete.setString(1, data);
            if (authorized) {
                amberFlareDelete.executeUpdate();
            }
        } finally {
            amberFlareConnection.close();
        }
    }
}
