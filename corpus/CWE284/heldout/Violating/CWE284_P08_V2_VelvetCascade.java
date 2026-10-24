import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_VelvetCascade {

    public void deleteVelvetCascadeAccount() throws SQLException {
        String data;
        if (true) {
            data = System.getenv("VELVET_CASCADE_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_VelvetCascadeSink()).applyVelvetCascadeDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_VelvetCascadeSink {
    public void applyVelvetCascadeDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
        Connection velvetCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetCascade");
        try {
            PreparedStatement velvetCascadeDelete = velvetCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetCascadeDelete.setString(1, data);
            if (authorized) {
                System.err.println("delete of account " + data + " refused");
            } else {
                velvetCascadeDelete.executeUpdate();
            }
        } finally {
            velvetCascadeConnection.close();
        }
    }
}
