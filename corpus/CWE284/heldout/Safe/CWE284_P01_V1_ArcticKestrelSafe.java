import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_ArcticKestrelSafe {

    public void deleteArcticKestrelAccount() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_KESTREL_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection arcticKestrelConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticKestrel");
        try {
            PreparedStatement arcticKestrelDelete = arcticKestrelConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticKestrelDelete.setString(1, data);
            if (authorized) {
                arcticKestrelDelete.executeUpdate();
            }
        } finally {
            arcticKestrelConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
