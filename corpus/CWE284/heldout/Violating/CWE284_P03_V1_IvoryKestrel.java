import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_IvoryKestrel {

    private void applyIvoryKestrelDeletion(String data, boolean authorized) throws SQLException {
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
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyIvoryKestrelDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
