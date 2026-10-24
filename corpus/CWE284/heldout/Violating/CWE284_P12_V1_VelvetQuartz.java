import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P12_V1_VelvetQuartz {

    public void deleteVelvetQuartzAccount() throws SQLException {
        String data;
        data = System.getenv("VELVET_QUARTZ_ACCOUNT_ID");
        boolean authorized = isAuthorized(data);
        CWE284_P12_V1_VelvetQuartzBase baseObject = new CWE284_P12_V1_VelvetQuartzRemover();
        baseObject.action(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

abstract class CWE284_P12_V1_VelvetQuartzBase {
    public abstract void action(String data, boolean authorized) throws SQLException;
}

class CWE284_P12_V1_VelvetQuartzRemover extends CWE284_P12_V1_VelvetQuartzBase {
    public void action(String data, boolean authorized) throws SQLException {
        Connection velvetQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetQuartz");
        try {
            PreparedStatement velvetQuartzDelete = velvetQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetQuartzDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                velvetQuartzDelete.executeUpdate();
            }
        } finally {
            velvetQuartzConnection.close();
        }
    }
}
