import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P10_V2_AmberCascade {

    public static String data;

    public static boolean authorized;

    public void deleteAmberCascadeAccount() throws SQLException {
        data = null;
        for (int j = 0; j < 1; j++) {
            data = System.getenv("AMBER_CASCADE_ACCOUNT_ID");
        }
        authorized = isAuthorized(data);
        (new CWE284_P10_V2_AmberCascadeSink()).applyAmberCascadeDeletion();
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P10_V2_AmberCascadeSink {
    public void applyAmberCascadeDeletion() throws SQLException {
        String data = CWE284_P10_V2_AmberCascade.data;
        boolean authorized = CWE284_P10_V2_AmberCascade.authorized;
        Connection amberCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberCascade");
        try {
            PreparedStatement amberCascadeDelete = amberCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberCascadeDelete.setString(1, data);
            amberCascadeDelete.executeUpdate();
            if (!authorized) {
                throw new SecurityException("delete of account " + data + " is not authorized");
            }
        } finally {
            amberCascadeConnection.close();
        }
    }
}
