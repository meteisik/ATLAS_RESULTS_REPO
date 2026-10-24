import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_OnyxCometSafe {
    private static final boolean PRIVATE_STATIC_FINAL_TRUE = true;

    public void deleteOnyxCometAccount() throws SQLException {
        String data;
        if (PRIVATE_STATIC_FINAL_TRUE) {
            data = System.getenv("ONYX_COMET_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_OnyxCometSafeSink()).applyOnyxCometDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_OnyxCometSafeSink {
    public void applyOnyxCometDeletion(String data, boolean authorized) throws SQLException {
        Connection onyxCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:onyxComet");
        try {
            PreparedStatement onyxCometDelete = onyxCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            onyxCometDelete.setString(1, data);
            if (authorized) {
                onyxCometDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            onyxCometConnection.close();
        }
    }
}
