import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_ArcticOrbitSafe {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteArcticOrbitAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("ARCTIC_ORBIT_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_ArcticOrbitSafeBase baseObject = new CWE284_P12_V2_ArcticOrbitSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_ArcticOrbitSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_ArcticOrbitSafeRemover extends CWE284_P12_V2_ArcticOrbitSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection arcticOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:arcticOrbit");
        try {
            PreparedStatement arcticOrbitDelete = arcticOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            arcticOrbitDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                arcticOrbitDelete.executeUpdate();
            }
        } finally {
            arcticOrbitConnection.close();
        }
    }
}
