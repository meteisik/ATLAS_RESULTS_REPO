import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P09_V2_AmberCascade {

    static class Container {
        public String accountId;
        public boolean authorized;
    }

    public void deleteAmberCascadeAccount() throws SQLException {
        String data;
        switch (7) {
        case 7:
            data = System.getenv("AMBER_CASCADE_ACCOUNT_ID");
            break;
        default:
            data = null;
            break;
        }
        Container request = new Container();
        request.accountId = data;
        request.authorized = isAuthorized(data);
        (new CWE284_P09_V2_AmberCascadeSink()).applyAmberCascadeDeletion(request);
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}

class CWE284_P09_V2_AmberCascadeSink {
    public void applyAmberCascadeDeletion(CWE284_P09_V2_AmberCascade.Container request) throws SQLException {
        String data = request.accountId;
        boolean authorized = request.authorized;
        Connection amberCascadeConnection = DriverManager.getConnection("jdbc:hsqldb:mem:amberCascade");
        try {
            PreparedStatement amberCascadeDelete = amberCascadeConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
            amberCascadeDelete.setString(1, data);
            amberCascadeDelete.executeUpdate();
        } finally {
            amberCascadeConnection.close();
        }
    }
}
