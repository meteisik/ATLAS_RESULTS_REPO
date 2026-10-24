import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_VelvetFlare {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteVelvetFlareAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("VELVET_FLARE_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_VelvetFlareSink()).applyVelvetFlareDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_VelvetFlareSink {
    public void applyVelvetFlareDeletion(CWE284_P09_V2_VelvetFlare.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection velvetFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetFlare");
        try {
            PreparedStatement velvetFlareDelete = velvetFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetFlareDelete.setString(1, data);
            velvetFlareDelete.executeUpdate();
        } finally {
            velvetFlareConnection.close();
        }
    }
}
