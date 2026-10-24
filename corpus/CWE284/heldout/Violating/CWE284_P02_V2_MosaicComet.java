import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;

public class CWE284_P02_V2_MosaicComet {

    public void deleteMosaicCometAccount() throws SQLException {
        String dataCopy;
        boolean authorizedCopy;
        {
            String data;
            switch (7) {
            case 7:
                data = System.getenv("MOSAIC_COMET_ACCOUNT_ID");
                break;
            default:
                data = null;
                break;
            }
            dataCopy = data;
            authorizedCopy = isAuthorized(data);
        }
        {
            String data = dataCopy;
            boolean authorized = authorizedCopy;
            Connection mosaicCometConnection = DriverManager.getConnection("jdbc:hsqldb:mem:mosaicComet");
            try {
                PreparedStatement mosaicCometDelete = mosaicCometConnection.prepareStatement("DELETE FROM accounts WHERE id = ?");
                mosaicCometDelete.setString(1, data);
                mosaicCometDelete.executeUpdate();
                if (!authorized) {
                    throw new SecurityException("delete of account " + data + " is not authorized");
                }
            } finally {
                mosaicCometConnection.close();
            }
        }
    }

    private boolean isAuthorized(String accountId) {
        String operator = System.getProperty("user.name");
        return operator != null && operator.equals(accountId);
    }
}
