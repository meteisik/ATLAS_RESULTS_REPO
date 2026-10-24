import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V2_SaffronFlare {
    private static boolean privateReturnsTrue() { return true; }

    private String saffronFlareAccountId;

    private boolean saffronFlareAuthorized;

    private void applySaffronFlareDeletion() throws SQLException {
        String data = saffronFlareAccountId;
        boolean authorized = saffronFlareAuthorized;
        Connection saffronFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronFlare");
        try {
            PreparedStatement saffronFlareDelete = saffronFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronFlareDelete.setString(1, data);
            saffronFlareDelete.executeUpdate();
        } finally {
            saffronFlareConnection.close();
        }
    }

    public void deleteSaffronFlareAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("SAFFRON_FLARE_ACCOUNT_ID");
        } else {
            data = null;
        }
        saffronFlareAccountId = data;
        saffronFlareAuthorized = isAuthorized(data);
        applySaffronFlareDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
