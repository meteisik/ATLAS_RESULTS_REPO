import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_IvoryOrbit {

    private void applyIvoryOrbitDeletion(String data, boolean authorized) throws SQLException {
        Connection ivoryOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:ivoryOrbit");
        try {
            PreparedStatement ivoryOrbitDelete = ivoryOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            ivoryOrbitDelete.setString(1, data);
            if (authorized) {
                ivoryOrbitDelete.executeUpdate();
            }
        } finally {
            ivoryOrbitConnection.close();
        }
    }

    public void deleteIvoryOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("IVORY_ORBIT_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(requester);
        applyIvoryOrbitDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
