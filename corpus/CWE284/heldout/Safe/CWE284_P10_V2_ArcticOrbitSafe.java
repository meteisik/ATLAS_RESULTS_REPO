import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_ArcticOrbitSafe {

    public static String data;

    public static boolean authorized;

    public void deleteArcticOrbitAccount() throws SQLException {
        if (true) {
            data = System.getenv("ARCTIC_ORBIT_ACCOUNT_ID");
        } else {
            data = null;
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_ArcticOrbitSafeSink()).applyArcticOrbitDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_ArcticOrbitSafeSink {
    public void applyArcticOrbitDeletion() throws SQLException {
        String data = CWE284_P10_V2_ArcticOrbitSafe.data;
        boolean authorized = CWE284_P10_V2_ArcticOrbitSafe.authorized;
        Connection arcticOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticOrbit");
        try {
            PreparedStatement arcticOrbitDelete = arcticOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticOrbitDelete.setString(1, data);
            if (authorized) {
                arcticOrbitDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            arcticOrbitConnection.close();
        }
    }
}
