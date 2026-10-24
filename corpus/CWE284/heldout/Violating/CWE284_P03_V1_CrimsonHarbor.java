import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_CrimsonHarbor {

    private void applyCrimsonHarborDeletion(String data, boolean authorized) throws SQLException {
        Connection crimsonHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonHarbor");
        try {
            PreparedStatement crimsonHarborDelete = crimsonHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonHarborDelete.setString(1, data);
            if (authorized) {
                crimsonHarborDelete.executeUpdate();
            }
        } finally {
            crimsonHarborConnection.close();
        }
    }

    public void deleteCrimsonHarborAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_HARBOR_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyCrimsonHarborDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
