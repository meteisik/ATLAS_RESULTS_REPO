import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_CobaltOrbit {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteCobaltOrbitAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("COBALT_ORBIT_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_CobaltOrbitBase baseObject = new CWE284_P12_V2_CobaltOrbitRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_CobaltOrbitBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_CobaltOrbitRemover extends CWE284_P12_V2_CobaltOrbitBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection cobaltOrbitConnection = DriverManager.getConnection("jdbc:hsqldb:mem:cobaltOrbit");
        try {
            PreparedStatement cobaltOrbitDelete = cobaltOrbitConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            cobaltOrbitDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                cobaltOrbitDelete.executeUpdate();
            }
        } finally {
            cobaltOrbitConnection.close();
        }
    }
}
