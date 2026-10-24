import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_IvoryHelix {

    private void applyIvoryHelixDeletion(String data, boolean authorized) throws SQLException {
        Connection ivoryHelixConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryHelix");
        try {
            PreparedStatement ivoryHelixDelete = ivoryHelixConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryHelixDelete.setString(1, data);
            if (authorized) {
                ivoryHelixDelete.executeUpdate();
            }
        } finally {
            ivoryHelixConnection.close();
        }
    }

    public void deleteIvoryHelixAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_HELIX_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyIvoryHelixDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
