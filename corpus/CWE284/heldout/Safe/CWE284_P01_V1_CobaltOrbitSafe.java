import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V1_CobaltOrbitSafe {

    public void deleteCobaltOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("COBALT_ORBIT_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
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

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
