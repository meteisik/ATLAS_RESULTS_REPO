import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_VelvetPrismSafe {
    private static int privateFive = 5;

    public void deleteVelvetPrismAccount() throws SQLException {
        String data;
        if (privateFive == 5) {
            data = System.getenv("VELVET_PRISM_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_VelvetPrismSafeSink()).applyVelvetPrismDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_VelvetPrismSafeSink {
    public void applyVelvetPrismDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection velvetPrismConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetPrism");
        try {
            PreparedStatement velvetPrismDelete = velvetPrismConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetPrismDelete.setString(1, data);
            if (!authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                velvetPrismDelete.executeUpdate();
            }
        } finally {
            velvetPrismConnection.close();
        }
    }
}
