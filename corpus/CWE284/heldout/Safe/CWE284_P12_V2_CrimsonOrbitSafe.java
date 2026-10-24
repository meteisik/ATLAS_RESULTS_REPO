import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_CrimsonOrbitSafe {

    public void deleteCrimsonOrbitAccount() throws SQLException {
        String data;
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("CRIMSON_ORBIT_ACCOUNT_ID");
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_CrimsonOrbitSafeBase baseObject = new CWE284_P12_V2_CrimsonOrbitSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_CrimsonOrbitSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_CrimsonOrbitSafeRemover extends CWE284_P12_V2_CrimsonOrbitSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
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
}
