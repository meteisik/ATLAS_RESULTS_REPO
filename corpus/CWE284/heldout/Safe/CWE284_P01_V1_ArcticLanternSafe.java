import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_ArcticLanternSafe {

    public void deleteArcticLanternAccount() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_LANTERN_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection arcticLanternConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticLantern");
        try {
            PreparedStatement arcticLanternDelete = arcticLanternConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticLanternDelete.setString(1, data);
            if (authorized) {
                arcticLanternDelete.executeUpdate();
            }
        } finally {
            arcticLanternConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
