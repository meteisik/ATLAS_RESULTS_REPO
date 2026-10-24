import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P01_V2_CrimsonOrbit {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteCrimsonOrbitAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("CRIMSON_ORBIT_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        Connection crimsonOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonOrbit");
        try {
            PreparedStatement crimsonOrbitDelete = crimsonOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonOrbitDelete.setString(1, data);
            crimsonOrbitDelete.executeUpdate();
        } finally {
            crimsonOrbitConnection.close();
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
