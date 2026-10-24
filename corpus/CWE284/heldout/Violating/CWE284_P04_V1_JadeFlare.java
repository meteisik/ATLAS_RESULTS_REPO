import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_JadeFlare {

    private boolean checkJadeFlareAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteJadeFlareAccount() throws SQLException {
        String data;
        data = System.getenv("JADE_FLARE_ACCOUNT_ID");
        boolean authorized = checkJadeFlareAccess(data);
        Connection jadeFlareConnection = DriverManager.getConnection("jdbc:hsqldb:mem:jadeFlare");
        try {
            PreparedStatement jadeFlareDelete = jadeFlareConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            jadeFlareDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                jadeFlareDelete.executeUpdate();
            }
        } finally {
            jadeFlareConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
