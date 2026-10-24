import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_IvoryHelix {

    private boolean checkIvoryHelixAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteIvoryHelixAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_HELIX_ACCOUNT_ID");
        boolean authorized = checkIvoryHelixAccess(data);
        Connection ivoryHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryHelix");
        try {
            PreparedStatement ivoryHelixDelete = ivoryHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryHelixDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                ivoryHelixDelete.executeUpdate();
            }
        } finally {
            ivoryHelixConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
