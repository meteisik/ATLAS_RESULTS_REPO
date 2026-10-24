import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_IvoryKestrelSafe {

    private String ivoryKestrelAccountId;

    private boolean ivoryKestrelAuthorized;

    private void applyIvoryKestrelDeletion() throws SQLException {
        String data = ivoryKestrelAccountId;
        boolean authorized = ivoryKestrelAuthorized;
        Connection ivoryKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryKestrel");
        try {
            PreparedStatement ivoryKestrelDelete = ivoryKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryKestrelDelete.setString(1, data);
            if (authorized) {
                ivoryKestrelDelete.executeUpdate();
            }
        } finally {
            ivoryKestrelConnection.close();
        }
    }

    public void deleteIvoryKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_KESTREL_ACCOUNT_ID");
        ivoryKestrelAccountId = data;
        ivoryKestrelAuthorized = isAuthorized(data);
        applyIvoryKestrelDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
