import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_VelvetQuartzSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteVelvetQuartzAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("VELVET_QUARTZ_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_VelvetQuartzSafeSink()).applyVelvetQuartzDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_VelvetQuartzSafeSink {
    public void applyVelvetQuartzDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection velvetQuartzConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetQuartz");
        try {
            PreparedStatement velvetQuartzDelete = velvetQuartzConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetQuartzDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                velvetQuartzDelete.executeUpdate();
            }
        } finally {
            velvetQuartzConnection.close();
        }
    }
}
