import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_IvoryKestrelSafe {
    private static int privateFive = 5;

    public void deleteIvoryKestrelAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("IVORY_KESTREL_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
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

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
