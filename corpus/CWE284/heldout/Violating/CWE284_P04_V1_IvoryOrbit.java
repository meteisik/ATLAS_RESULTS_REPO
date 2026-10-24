import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_IvoryOrbit {

    private boolean checkIvoryOrbitAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteIvoryOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_ORBIT_ACCOUNT_ID");
        boolean authorized = checkIvoryOrbitAccess(data);
        Connection ivoryOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryOrbit");
        try {
            PreparedStatement ivoryOrbitDelete = ivoryOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryOrbitDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                ivoryOrbitDelete.executeUpdate();
            }
        } finally {
            ivoryOrbitConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
