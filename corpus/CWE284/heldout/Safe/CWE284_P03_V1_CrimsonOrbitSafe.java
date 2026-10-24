import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P03_V1_CrimsonOrbitSafe {

    private void applyCrimsonOrbitDeletion(String data, boolean authorized) throws SQLException {
        Connection crimsonOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonOrbit");
        try {
            PreparedStatement crimsonOrbitDelete = crimsonOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonOrbitDelete.setString(1, data);
            if (authorized) {
                crimsonOrbitDelete.executeUpdate();
            }
        } finally {
            crimsonOrbitConnection.close();
        }
    }

    public void deleteCrimsonOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_ORBIT_ACCOUNT_ID");
        String requester = System.getProperty("user.name");
        boolean authorized = isAuthorized(data);
        applyCrimsonOrbitDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
