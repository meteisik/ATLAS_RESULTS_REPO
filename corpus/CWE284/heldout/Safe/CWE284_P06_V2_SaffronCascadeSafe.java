import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P06_V2_SaffronCascadeSafe {
    private static boolean privateReturnsTrue() { return true; }

    public void deleteSaffronCascadeAccount() throws SQLException {
        String data;
        if (privateReturnsTrue()) {
            data = System.getenv("SAFFRON_CASCADE_ACCOUNT_ID");
        } else {
            data = null;
        }
        boolean authorized = isAuthorized(data);
        (new CWE284_P06_V2_SaffronCascadeSafeSink()).applySaffronCascadeDeletion(data, authorized);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P06_V2_SaffronCascadeSafeSink {
    public void applySaffronCascadeDeletion(String data, boolean authorized) throws SQLException {
        Connection saffronCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:saffronCascade");
        try {
            PreparedStatement saffronCascadeDelete = saffronCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            saffronCascadeDelete.setString(1, data);
            if (authorized) {
                saffronCascadeDelete.executeUpdate();
            } else {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            saffronCascadeConnection.close();
        }
    }
}
