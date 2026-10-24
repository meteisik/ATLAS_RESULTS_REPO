import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_ArcticHarborSafe {

    public void deleteArcticHarborAccount() throws SQLException {
        String data;
        data = System.getenv("ARCTIC_HARBOR_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection arcticHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticHarbor");
        try {
            PreparedStatement arcticHarborDelete = arcticHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticHarborDelete.setString(1, data);
            if (authorized) {
                arcticHarborDelete.executeUpdate();
            }
        } finally {
            arcticHarborConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
