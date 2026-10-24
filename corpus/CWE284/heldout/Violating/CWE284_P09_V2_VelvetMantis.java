import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_VelvetMantis {
    private static boolean privateReturnsTrue() { return true; }

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteVelvetMantisAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("VELVET_MANTIS_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_VelvetMantisSink()).applyVelvetMantisDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_VelvetMantisSink {
    public void applyVelvetMantisDeletion(CWE284_P09_V2_VelvetMantis.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection velvetMantisConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetMantis");
        try {
            PreparedStatement velvetMantisDelete = velvetMantisConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetMantisDelete.setString(1, data);
            velvetMantisDelete.executeUpdate();
        } finally {
            velvetMantisConnection.close();
        }
    }
}
