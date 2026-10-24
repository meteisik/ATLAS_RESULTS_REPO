import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_IvoryHarbor {

    private boolean checkIvoryHarborAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteIvoryHarborAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_HARBOR_ACCOUNT_ID");
        boolean authorized = checkIvoryHarborAccess(data);
        Connection ivoryHarborConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryHarbor");
        try {
            PreparedStatement ivoryHarborDelete = ivoryHarborConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryHarborDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
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
