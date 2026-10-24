import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_JadeFlare {

    public void deleteJadeFlareAccount() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("JADE_FLARE_ACCOUNT_ID");
        }
        boolean authorized = isAuthorized(data);
        Connection jadeFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeFlare");
        try {
            PreparedStatement jadeFlareDelete = jadeFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeFlareDelete.setString(1, data);
            jadeFlareDelete.executeUpdate();
        } finally {
            jadeFlareConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
