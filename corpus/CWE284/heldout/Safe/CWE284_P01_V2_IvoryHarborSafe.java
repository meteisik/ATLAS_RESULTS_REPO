import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_IvoryHarborSafe {
    private static boolean privateTrue = true;

    public void deleteIvoryHarborAccount() throws SQLException {
        String data;
        if (privateTrue) {
            data = System.getenv("IVORY_HARBOR_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection ivoryHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryHarbor");
        try {
            PreparedStatement ivoryHarborDelete = ivoryHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryHarborDelete.setString(1, data);
            if (authorized) {
                ivoryHarborDelete.executeUpdate();
            }
        } finally {
            ivoryHarborConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
