import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_IvoryKestrelSafe {

    private boolean checkIvoryKestrelAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteIvoryKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_KESTREL_ACCOUNT_ID");
        boolean authorized = checkIvoryKestrelAccess(data);
        Connection ivoryKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryKestrel");
        try {
            PreparedStatement ivoryKestrelDelete = ivoryKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryKestrelDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                ivoryKestrelDelete.executeUpdate();
            }
        } finally {
            ivoryKestrelConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
