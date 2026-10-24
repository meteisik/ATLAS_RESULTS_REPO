import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V2_CrimsonRavenSafe {

    public void deleteCrimsonRavenAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("CRIMSON_RAVEN_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        CWE284_P12_V2_CrimsonRavenSafeBase baseObject = new CWE284_P12_V2_CrimsonRavenSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V2_CrimsonRavenSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V2_CrimsonRavenSafeRemover extends CWE284_P12_V2_CrimsonRavenSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection crimsonRavenConnection = DriverManager.getConnection("jdbc:hsqldb:mem:crimsonRaven");
        try {
            PreparedStatement crimsonRavenDelete = crimsonRavenConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            crimsonRavenDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                crimsonRavenDelete.executeUpdate();
            }
        } finally {
            crimsonRavenConnection.close();
        }
    }
}
