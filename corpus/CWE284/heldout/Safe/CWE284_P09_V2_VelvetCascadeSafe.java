import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_VelvetCascadeSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteVelvetCascadeAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("VELVET_CASCADE_ACCOUNT_ID");
        } else {
            data = null;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_VelvetCascadeSafeSink()).applyVelvetCascadeDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_VelvetCascadeSafeSink {
    public void applyVelvetCascadeDeletion(CWE284_P09_V2_VelvetCascadeSafe.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection velvetCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:velvetCascade");
        try {
            PreparedStatement velvetCascadeDelete = velvetCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            velvetCascadeDelete.setString(1, data);
            if (authorized) {
                velvetCascadeDelete.executeUpdate();
            }
        } finally {
            velvetCascadeConnection.close();
        }
    }
}
