import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P04_V1_CrimsonOrbitSafe {

    private boolean checkCrimsonOrbitAccess(String accountId) {
        boolean authorized = isAuthorized(accountId);
        return authorized;
    }

    public void deleteCrimsonOrbitAccount() throws SQLException {
        String data;
        data = System.getenv("CRIMSON_ORBIT_ACCOUNT_ID");
        boolean authorized = checkCrimsonOrbitAccess(data);
        Connection crimsonOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonOrbit");
        try {
            PreparedStatement crimsonOrbitDelete = crimsonOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonOrbitDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                crimsonOrbitDelete.executeUpdate();
            }
        } finally {
            crimsonOrbitConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
