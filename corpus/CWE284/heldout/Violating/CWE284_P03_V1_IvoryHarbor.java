import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_IvoryHarbor {

    private void applyIvoryHarborDeletion(String data, boolean authorized) throws SQLException {
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

    public void deleteIvoryHarborAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_HARBOR_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyIvoryHarborDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
