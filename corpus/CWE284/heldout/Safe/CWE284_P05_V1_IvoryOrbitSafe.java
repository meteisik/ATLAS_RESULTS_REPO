import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P05_V1_IvoryOrbitSafe {

    private String ivoryOrbitAccountId;

    private boolean ivoryOrbitAuthorized;

    private void applyIvoryOrbitDeletion() throws SQLException {
        String data = ivoryOrbitAccountId;
        boolean authorized = ivoryOrbitAuthorized;
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
        ivoryOrbitAccountId = data;
        ivoryOrbitAuthorized = isAuthorized(data);
        applyIvoryOrbitDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
