import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_VelvetMantis {

    public void deleteVelvetMantisAccount() throws SQLException {
        String data;
        data = System.getenv("VELVET_MANTIS_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_VelvetMantisBase baseObject = new CWE284_P12_V1_VelvetMantisRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_VelvetMantisBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_VelvetMantisRemover extends CWE284_P12_V1_VelvetMantisBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection velvetMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetMantis");
        try {
            PreparedStatement velvetMantisDelete = velvetMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetMantisDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                velvetMantisDelete.executeUpdate();
            }
        } finally {
            velvetMantisConnection.close();
        }
    }
}
