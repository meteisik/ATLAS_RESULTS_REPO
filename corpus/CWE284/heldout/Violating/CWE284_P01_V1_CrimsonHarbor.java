import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_CrimsonHarbor {

    public void deleteCrimsonHarborAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_HARBOR_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        Connection crimsonHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonHarbor");
        try {
            PreparedStatement crimsonHarborDelete = crimsonHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonHarborDelete.setString(1, data);
            crimsonHarborDelete.executeUpdate();
        } finally {
            crimsonHarborConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
