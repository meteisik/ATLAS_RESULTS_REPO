import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_CobaltOrbitSafe {

    private void applyCobaltOrbitDeletion(String data, boolean authorized) throws SQLException {
        Connection cobaltOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltOrbit");
        try {
            PreparedStatement cobaltOrbitDelete = cobaltOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            cobaltOrbitDelete.setString(1, data);
            if (authorized) {
                cobaltOrbitDelete.executeUpdate();
            }
        } finally {
            cobaltOrbitConnection.close();
        }
    }

    public void deleteCobaltOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("COBALT_ORBIT_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyCobaltOrbitDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
