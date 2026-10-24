import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_IvoryRavenSafe {

    private boolean checkIvoryRavenAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteIvoryRavenAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_RAVEN_ACCOUNT_ID");
        boolean authorized = checkIvoryRavenAccess(data);
        Connection ivoryRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryRaven");
        try {
            PreparedStatement ivoryRavenDelete = ivoryRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryRavenDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                ivoryRavenDelete.executeUpdate();
            }
        } finally {
            ivoryRavenConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
