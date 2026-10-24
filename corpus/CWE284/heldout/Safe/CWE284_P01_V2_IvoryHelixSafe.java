import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_IvoryHelixSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteIvoryHelixAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("IVORY_HELIX_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
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

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
