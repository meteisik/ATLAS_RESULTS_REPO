import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P08_V2_VelvetMantis {
    private static final int PRIVATE_STATIC_FINAL_FIVE = 5;

    public void deleteVelvetMantisAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_FIVE == 5) {
            data = System.getenv("VELVET_MANTIS_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean[] decisions = new boolean[5];
        decisions[2] = isAuthorized(data);
        (new CWE284_P08_V2_VelvetMantisSink()).applyVelvetMantisDeletion(data, decisions);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P08_V2_VelvetMantisSink {
    public void applyVelvetMantisDeletion(String data, boolean[] decisions) throws SQLException {
        boolean authorized = decisions[2];
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
