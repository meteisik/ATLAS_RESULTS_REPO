import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_VelvetMantisSafe {

    public void deleteVelvetMantisAccount() throws SQLException {
        String data;
        data = System.getenv("VELVET_MANTIS_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_VelvetMantisSafeBase baseObject = new CWE284_P12_V1_VelvetMantisSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_VelvetMantisSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_VelvetMantisSafeRemover extends CWE284_P12_V1_VelvetMantisSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection velvetMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetMantis");
        try {
            PreparedStatement velvetMantisDelete = velvetMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetMantisDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                velvetMantisDelete.executeUpdate();
            }
        } finally {
            velvetMantisConnection.close();
        }
    }
}
