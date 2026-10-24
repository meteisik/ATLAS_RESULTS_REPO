import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_AmberMantisSafe {

    public void deleteAmberMantisAccount() throws SQLException {
        String data;
        data = System.getenv("AMBER_MANTIS_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_AmberMantisSafeBase baseObject = new CWE284_P12_V1_AmberMantisSafeRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_AmberMantisSafeBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_AmberMantisSafeRemover extends CWE284_P12_V1_AmberMantisSafeBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection amberMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberMantis");
        try {
            PreparedStatement amberMantisDelete = amberMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberMantisDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                amberMantisDelete.executeUpdate();
            }
        } finally {
            amberMantisConnection.close();
        }
    }
}
